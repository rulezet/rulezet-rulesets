rule mal_macos_crossrat_client {
  meta:
    description = "Identify macOS CrossRAT client class"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.18"
    reference   = "https://objective-see.org/blog/blog_0x28.html"
    sample      = "d7e2bb4babf56a84febb822e7c304159367ba61c97afa30aa1e8d93686c1c6f0"
    DaysofYARA  = "77/100"

  strings:
    $jar   = "mediamgrs.jar"
    $name0 = "os.name"
    $name1 = "user.name"

  condition:
    uint32be(0) == 0xCAFEBABE and
    all of them
}