rule TTP_XOR_QUAD_CurrentVersionRun_9fcd {
  strings:
    $key_9fcd = { cc a2 [2] e8 ac [2] c3 80 [2] ed a2 [2] f9 b9 [2] f6 a3 [2] e8 be [2] ea bf [2] f1 b9 [2] ed be [2] f1 91 }

  condition:
    any of them
}