rule TTP_XOR_QUAD_CurrentVersionRun_b551 {
  strings:
    $key_b551 = { e6 3e [2] c2 30 [2] e9 1c [2] c7 3e [2] d3 25 [2] dc 3f [2] c2 22 [2] c0 23 [2] db 25 [2] c7 22 [2] db 0d }

  condition:
    any of them
}