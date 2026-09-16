rule TTP_XOR_QUAD_CurrentVersionRun_783c {
  strings:
    $key_783c = { 2b 53 [2] 0f 5d [2] 24 71 [2] 0a 53 [2] 1e 48 [2] 11 52 [2] 0f 4f [2] 0d 4e [2] 16 48 [2] 0a 4f [2] 16 60 }

  condition:
    any of them
}