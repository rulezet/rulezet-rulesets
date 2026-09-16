rule TTP_XOR_QUAD_CurrentVersionRun_aef9 {
  strings:
    $key_aef9 = { fd 96 [2] d9 98 [2] f2 b4 [2] dc 96 [2] c8 8d [2] c7 97 [2] d9 8a [2] db 8b [2] c0 8d [2] dc 8a [2] c0 a5 }

  condition:
    any of them
}