rule Heist
{
	meta:
    	md5_1 = "0ebf68bb15c2e36508cf3f46d32cf2e3"
        md5_2 = "c49b7a9681ad387922f14a1601652e5b"
        md5_3 = "e0350e67c526ffab0c97c5e04a6e9f12"
        md5_4 = "bb552a4bdc573566da897a651b9041e6"
        date = "11/4/2015"
        author = "Kevin Perlow"
        reference = "https://www.youtube.com/watch?v=DdkLY99HgAA"

	strings:

        $string = "Coded By - (Picasso)"

    condition:

        any of them

}