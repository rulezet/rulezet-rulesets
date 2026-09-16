rule TTP_XOR_QUAD_CurrentVersionRun_217f {
  strings:
    $key_217f = { 72 10 [2] 56 1e [2] 7d 32 [2] 53 10 [2] 47 0b [2] 48 11 [2] 56 0c [2] 54 0d [2] 4f 0b [2] 53 0c [2] 4f 23 }

  condition:
    any of them
}