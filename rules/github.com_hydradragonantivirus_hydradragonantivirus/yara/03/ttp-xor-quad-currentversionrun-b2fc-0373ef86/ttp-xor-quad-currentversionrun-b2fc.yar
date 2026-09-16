rule TTP_XOR_QUAD_CurrentVersionRun_b2fc {
  strings:
    $key_b2fc = { e1 93 [2] c5 9d [2] ee b1 [2] c0 93 [2] d4 88 [2] db 92 [2] c5 8f [2] c7 8e [2] dc 88 [2] c0 8f [2] dc a0 }

  condition:
    any of them
}