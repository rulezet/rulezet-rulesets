rule TTP_XOR_QUAD_CurrentVersionRun_b521 {
  strings:
    $key_b521 = { e6 4e [2] c2 40 [2] e9 6c [2] c7 4e [2] d3 55 [2] dc 4f [2] c2 52 [2] c0 53 [2] db 55 [2] c7 52 [2] db 7d }

  condition:
    any of them
}