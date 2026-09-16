rule TTP_XOR_QUAD_CurrentVersionRun_f942 {
  strings:
    $key_f942 = { aa 2d [2] 8e 23 [2] a5 0f [2] 8b 2d [2] 9f 36 [2] 90 2c [2] 8e 31 [2] 8c 30 [2] 97 36 [2] 8b 31 [2] 97 1e }

  condition:
    any of them
}