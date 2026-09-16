rule TTP_XOR_QUAD_CurrentVersionRun_393a {
  strings:
    $key_393a = { 6a 55 [2] 4e 5b [2] 65 77 [2] 4b 55 [2] 5f 4e [2] 50 54 [2] 4e 49 [2] 4c 48 [2] 57 4e [2] 4b 49 [2] 57 66 }

  condition:
    any of them
}