rule TTP_XOR_QUAD_CurrentVersionRun_3921 {
  strings:
    $key_3921 = { 6a 4e [2] 4e 40 [2] 65 6c [2] 4b 4e [2] 5f 55 [2] 50 4f [2] 4e 52 [2] 4c 53 [2] 57 55 [2] 4b 52 [2] 57 7d }

  condition:
    any of them
}