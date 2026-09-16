rule TTP_XOR_QUAD_CurrentVersionRun_e402 {
  strings:
    $key_e402 = { b7 6d [2] 93 63 [2] b8 4f [2] 96 6d [2] 82 76 [2] 8d 6c [2] 93 71 [2] 91 70 [2] 8a 76 [2] 96 71 [2] 8a 5e }

  condition:
    any of them
}