rule TTP_XOR_QUAD_CurrentVersionRun_b2ff {
  strings:
    $key_b2ff = { e1 90 [2] c5 9e [2] ee b2 [2] c0 90 [2] d4 8b [2] db 91 [2] c5 8c [2] c7 8d [2] dc 8b [2] c0 8c [2] dc a3 }

  condition:
    any of them
}