rule TTP_XOR_QUAD_CurrentVersionRun_3f0f {
  strings:
    $key_3f0f = { 6c 60 [2] 48 6e [2] 63 42 [2] 4d 60 [2] 59 7b [2] 56 61 [2] 48 7c [2] 4a 7d [2] 51 7b [2] 4d 7c [2] 51 53 }

  condition:
    any of them
}