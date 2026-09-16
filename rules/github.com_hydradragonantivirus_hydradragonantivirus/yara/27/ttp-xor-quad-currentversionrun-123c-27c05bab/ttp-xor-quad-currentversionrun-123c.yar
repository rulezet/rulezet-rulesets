rule TTP_XOR_QUAD_CurrentVersionRun_123c {
  strings:
    $key_123c = { 41 53 [2] 65 5d [2] 4e 71 [2] 60 53 [2] 74 48 [2] 7b 52 [2] 65 4f [2] 67 4e [2] 7c 48 [2] 60 4f [2] 7c 60 }

  condition:
    any of them
}