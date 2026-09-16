rule TTP_XOR_QUAD_CurrentVersionRun_b51e {
  strings:
    $key_b51e = { e6 71 [2] c2 7f [2] e9 53 [2] c7 71 [2] d3 6a [2] dc 70 [2] c2 6d [2] c0 6c [2] db 6a [2] c7 6d [2] db 42 }

  condition:
    any of them
}