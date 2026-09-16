rule TTP_XOR_QUAD_CurrentVersionRun_d91b {
  strings:
    $key_d91b = { 8a 74 [2] ae 7a [2] 85 56 [2] ab 74 [2] bf 6f [2] b0 75 [2] ae 68 [2] ac 69 [2] b7 6f [2] ab 68 [2] b7 47 }

  condition:
    any of them
}