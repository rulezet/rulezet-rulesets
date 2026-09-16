rule TTP_XOR_QUAD_CurrentVersionRun_b520 {
  strings:
    $key_b520 = { e6 4f [2] c2 41 [2] e9 6d [2] c7 4f [2] d3 54 [2] dc 4e [2] c2 53 [2] c0 52 [2] db 54 [2] c7 53 [2] db 7c }

  condition:
    any of them
}