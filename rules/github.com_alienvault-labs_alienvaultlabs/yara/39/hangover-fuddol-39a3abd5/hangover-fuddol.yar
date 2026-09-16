rule Hangover_Fuddol {
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}