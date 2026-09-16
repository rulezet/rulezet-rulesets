rule TTP_XOR_QUAD_CurrentVersionRun_b50d {
  strings:
    $key_b50d = { e6 62 [2] c2 6c [2] e9 40 [2] c7 62 [2] d3 79 [2] dc 63 [2] c2 7e [2] c0 7f [2] db 79 [2] c7 7e [2] db 51 }

  condition:
    any of them
}