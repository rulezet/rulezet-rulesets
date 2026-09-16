rule TTP_XOR_QUAD_CurrentVersionRun_f962 {
  strings:
    $key_f962 = { aa 0d [2] 8e 03 [2] a5 2f [2] 8b 0d [2] 9f 16 [2] 90 0c [2] 8e 11 [2] 8c 10 [2] 97 16 [2] 8b 11 [2] 97 3e }

  condition:
    any of them
}