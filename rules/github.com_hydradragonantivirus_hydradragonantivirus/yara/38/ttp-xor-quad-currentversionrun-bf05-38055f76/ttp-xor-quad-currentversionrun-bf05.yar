rule TTP_XOR_QUAD_CurrentVersionRun_bf05 {
  strings:
    $key_bf05 = { ec 6a [2] c8 64 [2] e3 48 [2] cd 6a [2] d9 71 [2] d6 6b [2] c8 76 [2] ca 77 [2] d1 71 [2] cd 76 [2] d1 59 }

  condition:
    any of them
}