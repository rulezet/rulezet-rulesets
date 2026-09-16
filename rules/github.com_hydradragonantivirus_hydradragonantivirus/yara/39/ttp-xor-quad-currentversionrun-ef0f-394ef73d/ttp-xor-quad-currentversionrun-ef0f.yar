rule TTP_XOR_QUAD_CurrentVersionRun_ef0f {
  strings:
    $key_ef0f = { bc 60 [2] 98 6e [2] b3 42 [2] 9d 60 [2] 89 7b [2] 86 61 [2] 98 7c [2] 9a 7d [2] 81 7b [2] 9d 7c [2] 81 53 }

  condition:
    any of them
}