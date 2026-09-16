rule TTP_XOR_QUAD_CurrentVersionRun_b56d {
  strings:
    $key_b56d = { e6 02 [2] c2 0c [2] e9 20 [2] c7 02 [2] d3 19 [2] dc 03 [2] c2 1e [2] c0 1f [2] db 19 [2] c7 1e [2] db 31 }

  condition:
    any of them
}