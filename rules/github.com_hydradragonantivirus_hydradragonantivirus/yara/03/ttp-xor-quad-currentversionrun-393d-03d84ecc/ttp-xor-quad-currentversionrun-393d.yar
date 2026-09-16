rule TTP_XOR_QUAD_CurrentVersionRun_393d {
  strings:
    $key_393d = { 6a 52 [2] 4e 5c [2] 65 70 [2] 4b 52 [2] 5f 49 [2] 50 53 [2] 4e 4e [2] 4c 4f [2] 57 49 [2] 4b 4e [2] 57 61 }

  condition:
    any of them
}