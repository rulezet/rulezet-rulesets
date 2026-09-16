rule TTP_XOR_QUAD_CurrentVersionRun_223d {
  strings:
    $key_223d = { 71 52 [2] 55 5c [2] 7e 70 [2] 50 52 [2] 44 49 [2] 4b 53 [2] 55 4e [2] 57 4f [2] 4c 49 [2] 50 4e [2] 4c 61 }

  condition:
    any of them
}