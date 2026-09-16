rule iOSPegasusDetected
{
    strings:
        $a01 = "/private/var/root/test.app/data"
        $a02 = "/private/var/root/test.app/d/"
        $a03 = "/private/var/root/test.app"
        $a04 = "/private/var/tmp/crw"
        $a05 = "/private/var/tmp/cr"
        $a06 = "/private/var/tmp/st_data/"

    condition:
        any of them
}