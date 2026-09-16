rule TTP_XOR_QUAD_CurrentVersionRun_3c21 {
  strings:
    $key_3c21 = { 6f 4e [2] 4b 40 [2] 60 6c [2] 4e 4e [2] 5a 55 [2] 55 4f [2] 4b 52 [2] 49 53 [2] 52 55 [2] 4e 52 [2] 52 7d }

  condition:
    any of them
}