rule TTP_XOR_QUAD_CurrentVersionRun_bf3c {
  strings:
    $key_bf3c = { ec 53 [2] c8 5d [2] e3 71 [2] cd 53 [2] d9 48 [2] d6 52 [2] c8 4f [2] ca 4e [2] d1 48 [2] cd 4f [2] d1 60 }

  condition:
    any of them
}