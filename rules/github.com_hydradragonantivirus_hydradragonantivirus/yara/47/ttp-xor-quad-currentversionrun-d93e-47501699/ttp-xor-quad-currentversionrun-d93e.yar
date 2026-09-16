rule TTP_XOR_QUAD_CurrentVersionRun_d93e {
  strings:
    $key_d93e = { 8a 51 [2] ae 5f [2] 85 73 [2] ab 51 [2] bf 4a [2] b0 50 [2] ae 4d [2] ac 4c [2] b7 4a [2] ab 4d [2] b7 62 }

  condition:
    any of them
}