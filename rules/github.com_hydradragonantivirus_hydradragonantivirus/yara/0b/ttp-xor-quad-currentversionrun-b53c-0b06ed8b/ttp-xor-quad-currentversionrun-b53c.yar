rule TTP_XOR_QUAD_CurrentVersionRun_b53c {
  strings:
    $key_b53c = { e6 53 [2] c2 5d [2] e9 71 [2] c7 53 [2] d3 48 [2] dc 52 [2] c2 4f [2] c0 4e [2] db 48 [2] c7 4f [2] db 60 }

  condition:
    any of them
}