rule TTP_XOR_QUAD_CurrentVersionRun_9fd1 {
  strings:
    $key_9fd1 = { cc be [2] e8 b0 [2] c3 9c [2] ed be [2] f9 a5 [2] f6 bf [2] e8 a2 [2] ea a3 [2] f1 a5 [2] ed a2 [2] f1 8d }

  condition:
    any of them
}