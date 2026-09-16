rule TTP_XOR_QUAD_CurrentVersionRun_f922 {
  strings:
    $key_f922 = { aa 4d [2] 8e 43 [2] a5 6f [2] 8b 4d [2] 9f 56 [2] 90 4c [2] 8e 51 [2] 8c 50 [2] 97 56 [2] 8b 51 [2] 97 7e }

  condition:
    any of them
}