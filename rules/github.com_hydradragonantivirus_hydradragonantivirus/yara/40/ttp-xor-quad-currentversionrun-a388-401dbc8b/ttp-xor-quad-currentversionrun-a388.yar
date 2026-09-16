rule TTP_XOR_QUAD_CurrentVersionRun_a388 {
  strings:
    $key_a388 = { f0 e7 [2] d4 e9 [2] ff c5 [2] d1 e7 [2] c5 fc [2] ca e6 [2] d4 fb [2] d6 fa [2] cd fc [2] d1 fb [2] cd d4 }

  condition:
    any of them
}