rule TTP_XOR_QUAD_CurrentVersionRun_d912 {
  strings:
    $key_d912 = { 8a 7d [2] ae 73 [2] 85 5f [2] ab 7d [2] bf 66 [2] b0 7c [2] ae 61 [2] ac 60 [2] b7 66 [2] ab 61 [2] b7 4e }

  condition:
    any of them
}