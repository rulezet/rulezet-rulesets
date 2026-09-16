rule TTP_XOR_QUAD_CurrentVersionRun_bf0c {
  strings:
    $key_bf0c = { ec 63 [2] c8 6d [2] e3 41 [2] cd 63 [2] d9 78 [2] d6 62 [2] c8 7f [2] ca 7e [2] d1 78 [2] cd 7f [2] d1 50 }

  condition:
    any of them
}