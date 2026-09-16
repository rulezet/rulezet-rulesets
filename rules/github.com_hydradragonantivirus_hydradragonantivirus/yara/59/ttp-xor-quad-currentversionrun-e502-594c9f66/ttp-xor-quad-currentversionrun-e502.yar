rule TTP_XOR_QUAD_CurrentVersionRun_e502 {
  strings:
    $key_e502 = { b6 6d [2] 92 63 [2] b9 4f [2] 97 6d [2] 83 76 [2] 8c 6c [2] 92 71 [2] 90 70 [2] 8b 76 [2] 97 71 [2] 8b 5e }

  condition:
    any of them
}