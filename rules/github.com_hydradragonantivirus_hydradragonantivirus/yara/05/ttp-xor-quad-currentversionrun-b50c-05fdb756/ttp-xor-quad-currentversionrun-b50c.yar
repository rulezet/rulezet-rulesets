rule TTP_XOR_QUAD_CurrentVersionRun_b50c {
  strings:
    $key_b50c = { e6 63 [2] c2 6d [2] e9 41 [2] c7 63 [2] d3 78 [2] dc 62 [2] c2 7f [2] c0 7e [2] db 78 [2] c7 7f [2] db 50 }

  condition:
    any of them
}