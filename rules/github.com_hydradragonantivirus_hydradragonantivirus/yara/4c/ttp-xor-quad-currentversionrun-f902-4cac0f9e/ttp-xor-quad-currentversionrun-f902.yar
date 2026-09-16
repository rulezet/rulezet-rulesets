rule TTP_XOR_QUAD_CurrentVersionRun_f902 {
  strings:
    $key_f902 = { aa 6d [2] 8e 63 [2] a5 4f [2] 8b 6d [2] 9f 76 [2] 90 6c [2] 8e 71 [2] 8c 70 [2] 97 76 [2] 8b 71 [2] 97 5e }

  condition:
    any of them
}