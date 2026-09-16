rule TTP_XOR_QUAD_CurrentVersionRun_b55d {
  strings:
    $key_b55d = { e6 32 [2] c2 3c [2] e9 10 [2] c7 32 [2] d3 29 [2] dc 33 [2] c2 2e [2] c0 2f [2] db 29 [2] c7 2e [2] db 01 }

  condition:
    any of them
}