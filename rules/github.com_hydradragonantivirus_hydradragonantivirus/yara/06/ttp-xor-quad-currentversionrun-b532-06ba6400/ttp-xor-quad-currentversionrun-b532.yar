rule TTP_XOR_QUAD_CurrentVersionRun_b532 {
  strings:
    $key_b532 = { e6 5d [2] c2 53 [2] e9 7f [2] c7 5d [2] d3 46 [2] dc 5c [2] c2 41 [2] c0 40 [2] db 46 [2] c7 41 [2] db 6e }

  condition:
    any of them
}