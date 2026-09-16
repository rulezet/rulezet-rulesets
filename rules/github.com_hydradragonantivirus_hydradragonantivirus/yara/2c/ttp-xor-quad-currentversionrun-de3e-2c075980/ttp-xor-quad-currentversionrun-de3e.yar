rule TTP_XOR_QUAD_CurrentVersionRun_de3e {
  strings:
    $key_de3e = { 8d 51 [2] a9 5f [2] 82 73 [2] ac 51 [2] b8 4a [2] b7 50 [2] a9 4d [2] ab 4c [2] b0 4a [2] ac 4d [2] b0 62 }

  condition:
    any of them
}