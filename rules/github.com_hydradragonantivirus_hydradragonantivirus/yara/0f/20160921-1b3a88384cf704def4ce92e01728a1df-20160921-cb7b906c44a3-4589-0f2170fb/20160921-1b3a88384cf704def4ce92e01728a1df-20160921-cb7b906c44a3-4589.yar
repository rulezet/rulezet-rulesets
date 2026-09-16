rule _20160921_1b3a88384cf704def4ce92e01728a1df_20160921_cb7b906c44a3_4589 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash3       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"R" ascii
    $s2 = "on f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s3 = "on f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s4 = "Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s5 = "rn \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}