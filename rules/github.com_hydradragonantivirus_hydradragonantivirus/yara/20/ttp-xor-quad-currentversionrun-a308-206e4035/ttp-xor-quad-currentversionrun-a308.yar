rule TTP_XOR_QUAD_CurrentVersionRun_a308 {
  strings:
    $key_a308 = { f0 67 [2] d4 69 [2] ff 45 [2] d1 67 [2] c5 7c [2] ca 66 [2] d4 7b [2] d6 7a [2] cd 7c [2] d1 7b [2] cd 54 }

  condition:
    any of them
}