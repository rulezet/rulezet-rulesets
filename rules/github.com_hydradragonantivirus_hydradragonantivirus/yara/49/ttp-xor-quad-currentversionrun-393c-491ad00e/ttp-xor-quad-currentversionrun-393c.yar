rule TTP_XOR_QUAD_CurrentVersionRun_393c {
  strings:
    $key_393c = { 6a 53 [2] 4e 5d [2] 65 71 [2] 4b 53 [2] 5f 48 [2] 50 52 [2] 4e 4f [2] 4c 4e [2] 57 48 [2] 4b 4f [2] 57 60 }

  condition:
    any of them
}