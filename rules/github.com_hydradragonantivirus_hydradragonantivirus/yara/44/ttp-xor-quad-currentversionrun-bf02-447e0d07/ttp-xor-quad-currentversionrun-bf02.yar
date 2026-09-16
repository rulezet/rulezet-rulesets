rule TTP_XOR_QUAD_CurrentVersionRun_bf02 {
  strings:
    $key_bf02 = { ec 6d [2] c8 63 [2] e3 4f [2] cd 6d [2] d9 76 [2] d6 6c [2] c8 71 [2] ca 70 [2] d1 76 [2] cd 71 [2] d1 5e }

  condition:
    any of them
}