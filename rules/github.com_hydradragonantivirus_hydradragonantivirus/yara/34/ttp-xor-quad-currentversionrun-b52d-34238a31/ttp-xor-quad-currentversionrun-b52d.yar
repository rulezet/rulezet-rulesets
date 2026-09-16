rule TTP_XOR_QUAD_CurrentVersionRun_b52d {
  strings:
    $key_b52d = { e6 42 [2] c2 4c [2] e9 60 [2] c7 42 [2] d3 59 [2] dc 43 [2] c2 5e [2] c0 5f [2] db 59 [2] c7 5e [2] db 71 }

  condition:
    any of them
}