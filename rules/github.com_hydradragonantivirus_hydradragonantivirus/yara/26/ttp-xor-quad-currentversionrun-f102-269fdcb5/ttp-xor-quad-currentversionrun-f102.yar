rule TTP_XOR_QUAD_CurrentVersionRun_f102 {
  strings:
    $key_f102 = { a2 6d [2] 86 63 [2] ad 4f [2] 83 6d [2] 97 76 [2] 98 6c [2] 86 71 [2] 84 70 [2] 9f 76 [2] 83 71 [2] 9f 5e }

  condition:
    any of them
}