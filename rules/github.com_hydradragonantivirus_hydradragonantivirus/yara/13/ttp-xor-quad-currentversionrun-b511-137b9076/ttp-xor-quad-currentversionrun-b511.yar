rule TTP_XOR_QUAD_CurrentVersionRun_b511 {
  strings:
    $key_b511 = { e6 7e [2] c2 70 [2] e9 5c [2] c7 7e [2] d3 65 [2] dc 7f [2] c2 62 [2] c0 63 [2] db 65 [2] c7 62 [2] db 4d }

  condition:
    any of them
}