rule TTP_XOR_QUAD_CurrentVersionRun_381f {
  strings:
    $key_381f = { 6b 70 [2] 4f 7e [2] 64 52 [2] 4a 70 [2] 5e 6b [2] 51 71 [2] 4f 6c [2] 4d 6d [2] 56 6b [2] 4a 6c [2] 56 43 }

  condition:
    any of them
}