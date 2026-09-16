rule TTP_XOR_QUAD_CurrentVersionRun_aef0 {
  strings:
    $key_aef0 = { fd 9f [2] d9 91 [2] f2 bd [2] dc 9f [2] c8 84 [2] c7 9e [2] d9 83 [2] db 82 [2] c0 84 [2] dc 83 [2] c0 ac }

  condition:
    any of them
}