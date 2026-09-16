rule TTP_XOR_QUAD_CurrentVersionRun_393e {
  strings:
    $key_393e = { 6a 51 [2] 4e 5f [2] 65 73 [2] 4b 51 [2] 5f 4a [2] 50 50 [2] 4e 4d [2] 4c 4c [2] 57 4a [2] 4b 4d [2] 57 62 }

  condition:
    any of them
}